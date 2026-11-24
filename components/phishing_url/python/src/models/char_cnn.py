"""Character-level CNN for URLs, with an optional structural-feature branch.

    ids (B, L) --Embedding--> (B, E, L) --Conv1d k=3,5,7 + ReLU--> masked max-pool
        --> concat [+ Linear(features)] --> MLP --> 1 logit (phishing)

Padding is masked before pooling, so the output depends only on the real
characters: training can trim batches to their longest URL for speed, and the
edge build can use a fixed length of 256 with identical results. Only
Embedding / Conv1d / Linear / ReLU / max, which export cleanly to ExecuTorch.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import torch
from torch import nn

from src.preprocessing.feature_extractor import FeatureScaler
from src.preprocessing.tokenizer import PAD_ID, URLTokenizer

CHECKPOINT_FORMAT = 1


@dataclass
class CharCNNConfig:
    vocab_size: int
    embed_dim: int = 32
    channels: int = 128
    kernel_sizes: tuple[int, ...] = (3, 5, 7)
    hidden: int = 64
    dropout: float = 0.3
    num_features: int = 0          # 0 = plain char-CNN, >0 = hybrid
    feature_hidden: int = 32

    def __post_init__(self) -> None:
        self.kernel_sizes = tuple(int(k) for k in self.kernel_sizes)
        if self.vocab_size < 2 or self.embed_dim < 1 or self.channels < 1 or self.hidden < 1:
            raise ValueError("sizes must be positive")
        if not self.kernel_sizes or any(k < 1 or k % 2 == 0 for k in self.kernel_sizes):
            raise ValueError("kernel_sizes must be odd positive integers")
        if not 0.0 <= self.dropout < 1.0:
            raise ValueError("dropout must be in [0, 1)")
        if self.num_features < 0:
            raise ValueError("num_features must be >= 0")


class CharCNN(nn.Module):
    def __init__(self, config: CharCNNConfig) -> None:
        super().__init__()
        self.config = config
        c = config
        self.embed = nn.Embedding(c.vocab_size, c.embed_dim, padding_idx=PAD_ID)
        self.convs = nn.ModuleList(
            nn.Conv1d(c.embed_dim, c.channels, k, padding=k // 2) for k in c.kernel_sizes)
        self.features = (nn.Sequential(nn.Linear(c.num_features, c.feature_hidden), nn.ReLU())
                         if c.num_features else None)
        in_dim = c.channels * len(c.kernel_sizes) + (c.feature_hidden if c.num_features else 0)
        self.head = nn.Sequential(nn.Dropout(c.dropout), nn.Linear(in_dim, c.hidden), nn.ReLU(),
                                  nn.Dropout(c.dropout), nn.Linear(c.hidden, 1))

    def forward(self, ids: torch.Tensor, features: torch.Tensor | None = None) -> torch.Tensor:
        """ids: (B, L) int64 token ids. Returns (B,) logits; sigmoid = P(phishing)."""
        keep = (ids != PAD_ID).unsqueeze(1)                 # (B, 1, L)
        x = self.embed(ids).transpose(1, 2)                  # (B, E, L)
        # ReLU output is >= 0, so zeroing padded positions is an exact masked max.
        parts = [torch.relu(conv(x)).masked_fill(~keep, 0.0).amax(dim=2) for conv in self.convs]
        if self.features is not None:
            if features is None or features.shape != (ids.shape[0], self.config.num_features):
                raise ValueError("hybrid model needs features of shape (B, num_features)")
            parts.append(self.features(features))
        elif features is not None:
            raise ValueError("this model was built without a feature branch")
        return self.head(torch.cat(parts, dim=1)).squeeze(1)


def count_parameters(model: nn.Module) -> int:
    return sum(p.numel() for p in model.parameters())


def config_to_dict(config: CharCNNConfig) -> dict[str, Any]:
    d = asdict(config)
    d["kernel_sizes"] = list(config.kernel_sizes)
    return d


def load_checkpoint(path: str | Path, map_location: str | torch.device = "cpu"
                    ) -> tuple[CharCNN, URLTokenizer, FeatureScaler | None, dict[str, Any]]:
    """Load a best.pt written by src.training.train_cnn, ready for inference."""
    ckpt = torch.load(Path(path), map_location=map_location, weights_only=True)
    if ckpt.get("format_version") != CHECKPOINT_FORMAT or ckpt.get("model_type") != "char_cnn":
        raise ValueError("not a char_cnn checkpoint of a supported version")
    tokenizer = URLTokenizer.from_config(ckpt["tokenizer"])
    if tokenizer.fingerprint() != ckpt["tokenizer_fingerprint"]:
        raise ValueError("tokenizer fingerprint mismatch")
    scaler = FeatureScaler.from_config(ckpt["scaler"]) if ckpt.get("scaler") else None
    config = CharCNNConfig(**ckpt["model_config"])
    if (scaler is None) != (config.num_features == 0):
        raise ValueError("checkpoint scaler does not match the model's feature branch")
    model = CharCNN(config)
    model.load_state_dict(ckpt["state_dict"])
    model.eval()
    meta = {k: v for k, v in ckpt.items() if k not in ("state_dict",)}
    return model, tokenizer, scaler, meta
