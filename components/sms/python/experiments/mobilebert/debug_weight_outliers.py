"""Find outlier weights in the pretrained MobileBERT checkpoint."""

from __future__ import annotations

import torch
from transformers import AutoModel

from common import MODEL_NAME


def main() -> None:
    model = AutoModel.from_pretrained(MODEL_NAME)
    rows = []
    for name, param in model.named_parameters():
        p = param.detach().float()
        rows.append(
            (
                name,
                float(p.abs().max()),
                float(p.abs().mean()),
                float(p.min()),
                float(p.max()),
                tuple(p.shape),
            )
        )
    rows.sort(key=lambda row: row[1], reverse=True)
    print("Top 30 parameters by absolute max:")
    for row in rows[:30]:
        print(f"{row[0]:70s} absmax={row[1]:.4e} absmean={row[2]:.4e} shape={row[5]}")
    print("\nLayer 23 parameters:")
    for row in rows:
        if "layer.23." in row[0]:
            print(f"{row[0]:70s} absmax={row[1]:.4e} absmean={row[2]:.4e} shape={row[5]}")


if __name__ == "__main__":
    main()
