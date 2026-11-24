"""Train the character CNN (or the CNN + structural-feature hybrid).

    python -m src.training.train_cnn                          # full_url, plain CNN
    python -m src.training.train_cnn --model hybrid
    python -m src.training.train_cnn --device cuda            # fail instead of using the CPU

Safe to interrupt: after every epoch the full state is saved to
artifacts/runs/<run>/last.pt and the same command resumes from it. The best
epoch (highest validation PR-AUC) is kept in best.pt. Training stops early when
validation PR-AUC has not improved for --patience epochs.

The test split is only scored with --with-test (final comparison). Reports
contain aggregate numbers only, never URLs.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import torch
from torch import nn
from torch.utils.data import DataLoader, Dataset, Sampler

from src.models.char_cnn import (CHECKPOINT_FORMAT, CharCNN, CharCNNConfig, config_to_dict,
                                 count_parameters)
from src.preprocessing.feature_extractor import FeatureExtractor, FeatureScaler
from src.preprocessing.tokenizer import URLTokenizer

from .data import CACHE_DIR, MODES, SPLITS_DIR, SplitData, load_features, load_split
from .metrics import binary_metrics, slice_metrics

RUNS_DIR = Path("artifacts/runs")
REPORTS_DIR = Path("reports")
STATE_FORMAT = 1
# Changing any of these makes an old last.pt incompatible (epochs may be raised).
_RESUME_KEYS = ("mode", "model", "batch_size", "lr", "weight_decay", "seed", "embed_dim",
                "channels", "kernel_sizes", "hidden", "dropout", "max_length", "tail_length",
                "pos_weight")


@dataclass
class TrainConfig:
    mode: str = "full_url"
    model: str = "cnn"                    # "cnn" or "hybrid"
    epochs: int = 30
    batch_size: int = 256
    lr: float = 1e-3
    weight_decay: float = 1e-4
    patience: int = 5
    seed: int = 13
    embed_dim: int = 32
    channels: int = 128
    kernel_sizes: list = field(default_factory=lambda: [3, 5, 7])
    hidden: int = 64
    dropout: float = 0.3
    max_length: int = 256
    tail_length: int = 64
    pos_weight: float = 1.0               # >1 weighs phishing errors more

    def __post_init__(self) -> None:
        if self.mode not in MODES:
            raise ValueError(f"mode must be one of {MODES}")
        if self.model not in ("cnn", "hybrid"):
            raise ValueError("model must be 'cnn' or 'hybrid'")
        if self.epochs < 1 or self.batch_size < 1 or self.patience < 1:
            raise ValueError("epochs, batch_size and patience must be >= 1")
        if self.lr <= 0 or self.weight_decay < 0 or self.pos_weight <= 0:
            raise ValueError("lr and pos_weight must be > 0, weight_decay >= 0")


# --------------------------------------------------------------------- data
@dataclass
class Tensors:
    ids: torch.Tensor          # (N, max_length) uint8 on device
    lengths: torch.Tensor      # (N,) int64 on device
    features: torch.Tensor | None
    y: torch.Tensor            # (N,) float32 on device


def to_tensors(data: SplitData, tokenizer: URLTokenizer, scaler: FeatureScaler | None,
               device: torch.device, cache_dir: Path | None) -> Tensors:
    enc = tokenizer.encode_batch(data.texts)
    if tokenizer.vocab_size > 256:
        raise ValueError("vocabulary too large for uint8 storage")
    feats = None
    if scaler is not None:
        raw = load_features(data, scaler.feature_names, cache_dir)
        feats = torch.from_numpy(scaler.transform(raw)).to(device)
    return Tensors(torch.from_numpy(enc.ids.astype(np.uint8)).to(device),
                   torch.from_numpy(enc.lengths).to(device), feats,
                   torch.from_numpy(data.y.astype(np.float32)).to(device))


def _batch(t: Tensors, idx: torch.Tensor):
    width = max(int(t.lengths[idx].max()), 1)          # trim padding: masking makes this exact
    ids = t.ids[idx, :width].long()
    return ids, (None if t.features is None else t.features[idx]), t.y[idx]


class URLDataset(Dataset):
    """Tokenized URLs (+ scaled features) held on the training device.

    Indexed with a whole batch of row numbers at once (the DataLoader runs with
    batch_size=None and a batch sampler), so one batch is one vectorized slice
    instead of `batch_size` separate Python calls.
    """

    def __init__(self, tensors: Tensors):
        self.tensors = tensors

    def __len__(self) -> int:
        return len(self.tensors.y)

    def __getitem__(self, idx: torch.Tensor):
        return _batch(self.tensors, idx)


class ShuffledBatches(Sampler):
    """One random permutation per epoch (from `generator`), cut into batches."""

    def __init__(self, n: int, batch_size: int, generator: torch.Generator, device: torch.device):
        self.n, self.batch_size, self.generator, self.device = n, batch_size, generator, device

    def __len__(self) -> int:
        return -(-self.n // self.batch_size)

    def __iter__(self):
        perm = torch.randperm(self.n, generator=self.generator).to(self.device)
        for start in range(0, self.n, self.batch_size):
            yield perm[start:start + self.batch_size]


class OrderedBatches(Sampler):
    """Rows 0..n-1 in order, in batches (prediction keeps the input order)."""

    def __init__(self, n: int, batch_size: int, device: torch.device):
        self.n, self.batch_size, self.device = n, batch_size, device

    def __len__(self) -> int:
        return -(-self.n // self.batch_size)

    def __iter__(self):
        for start in range(0, self.n, self.batch_size):
            yield torch.arange(start, min(start + self.batch_size, self.n), device=self.device)


def make_loader(t: Tensors, batch_size: int, generator: torch.Generator | None = None) -> DataLoader:
    """Shuffled batches when a generator is given (training), ordered batches otherwise."""
    n, device = len(t.y), t.y.device
    sampler = (OrderedBatches(n, batch_size, device) if generator is None
               else ShuffledBatches(n, batch_size, generator, device))
    # Data already sits on the device: no worker processes, no pinned memory. Every
    # pass draws a worker seed from the loader's generator; a private one keeps that
    # draw away from the global RNG that dropout uses (training stays reproducible).
    return DataLoader(URLDataset(t), batch_size=None, sampler=sampler, num_workers=0,
                      generator=torch.Generator())


@torch.no_grad()
def predict_logits(model: CharCNN, t: Tensors, batch_size: int = 1024) -> np.ndarray:
    model.eval()
    out = [model(ids, feats).float().cpu() for ids, feats, _ in make_loader(t, batch_size)]
    return torch.cat(out).double().numpy()


def predict(model: CharCNN, t: Tensors, batch_size: int = 1024) -> np.ndarray:
    """Uncalibrated P(phishing): float32 sigmoid of the logits."""
    logits = torch.from_numpy(predict_logits(model, t, batch_size)).float()
    return torch.sigmoid(logits).double().numpy()


# --------------------------------------------------------------------- utils
def resolve_device(name: str) -> torch.device:
    if name == "auto":
        return torch.device("cuda" if torch.cuda.is_available() else "cpu")
    if name == "cuda" and not torch.cuda.is_available():
        raise RuntimeError("--device cuda requested but CUDA is not available "
                           "(run scripts/check_env.py)")
    return torch.device(name)


def _atomic_save(obj, path: Path) -> None:
    tmp = path.with_suffix(path.suffix + ".part")
    torch.save(obj, tmp)
    os.replace(tmp, path)


def _summary(m: dict) -> dict:
    r = m.get("recall_at_fpr", {})
    return {"pr_auc": m.get("pr_auc"), "roc_auc": m.get("roc_auc"),
            "recall_at_1pct_fpr": r.get("0.01", {}).get("recall"),
            "recall_at_0.1pct_fpr": r.get("0.001", {}).get("recall"), "ece": m.get("ece")}


def _baseline_reference(mode: str, reports_dir: Path) -> dict | None:
    path = reports_dir / f"baselines_{mode}.json"
    try:
        rep = json.loads(path.read_text(encoding="utf-8"))
        return {"model": "char_ngram_lr",
                **_summary(rep["models"]["char_ngram_lr"]["val"]["overall"])}
    except (OSError, KeyError, ValueError):
        return None


def _log(msg: str) -> None:
    print(f"{datetime.now().strftime('%H:%M:%S')} {msg}", flush=True)


# --------------------------------------------------------------------- main
def train(cfg: TrainConfig, *, splits: Path = SPLITS_DIR, run_dir: Path | None = None,
          device: str = "auto", with_test: bool = False, restart: bool = False,
          cache_dir: Path | None = CACHE_DIR, reports_dir: Path = REPORTS_DIR) -> dict:
    dev = resolve_device(device)
    run_dir = Path(run_dir or RUNS_DIR / f"{cfg.mode}_{cfg.model}")
    run_dir.mkdir(parents=True, exist_ok=True)
    last_path, best_path = run_dir / "last.pt", run_dir / "best.pt"
    _log(f"device {dev}" + (f" ({torch.cuda.get_device_name(dev)})" if dev.type == "cuda" else "")
         + f", run dir {run_dir}")
    if cfg.mode == "domain":
        _log("WARNING: domain split has a known subdomain shortcut (see README); "
             "treat its scores as optimistic")

    torch.manual_seed(cfg.seed)
    tokenizer = URLTokenizer(max_length=cfg.max_length, tail_length=cfg.tail_length)
    train_data = load_split(cfg.mode, "train", splits)
    val_data = load_split(cfg.mode, "val", splits)
    scaler = None
    if cfg.model == "hybrid":
        names = FeatureExtractor().feature_names
        scaler = FeatureScaler.fit(names, load_features(train_data, names, cache_dir))  # train only
    tr = to_tensors(train_data, tokenizer, scaler, dev, cache_dir)
    va = to_tensors(val_data, tokenizer, scaler, dev, cache_dir)
    _log(f"data: train {len(train_data)} ({int(train_data.y.sum())} phishing), "
         f"val {len(val_data)} ({int(val_data.y.sum())} phishing)")

    mcfg = CharCNNConfig(vocab_size=tokenizer.vocab_size, embed_dim=cfg.embed_dim,
                         channels=cfg.channels, kernel_sizes=tuple(cfg.kernel_sizes),
                         hidden=cfg.hidden, dropout=cfg.dropout,
                         num_features=0 if scaler is None else len(scaler.feature_names))
    model = CharCNN(mcfg).to(dev)
    opt = torch.optim.AdamW(model.parameters(), lr=cfg.lr, weight_decay=cfg.weight_decay)
    sched = torch.optim.lr_scheduler.ReduceLROnPlateau(opt, mode="max", factor=0.5, patience=1)
    loss_fn = nn.BCEWithLogitsLoss(pos_weight=torch.tensor(cfg.pos_weight, device=dev))
    gen = torch.Generator().manual_seed(cfg.seed)
    data_hashes = {"train": train_data.file_sha256, "val": val_data.file_sha256}

    state = {"epoch": 0, "best_pr_auc": -1.0, "best_epoch": None, "bad_epochs": 0,
             "stopped_early": False, "history": []}
    if last_path.exists() and not restart:
        ck = torch.load(last_path, map_location=dev, weights_only=True)
        old = ck["config"]
        changed = [k for k in _RESUME_KEYS if old.get(k) != asdict(cfg).get(k)]
        if ck.get("state_format") != STATE_FORMAT or changed or ck["data_sha256"] != data_hashes:
            raise RuntimeError(
                f"{last_path} belongs to a different run (changed: {changed or 'data/format'}); "
                "use --restart to start over or --run-dir for a new run")
        model.load_state_dict(ck["model"])
        opt.load_state_dict(ck["optimizer"])
        sched.load_state_dict(ck["scheduler"])
        gen.set_state(ck["generator"])
        torch.set_rng_state(ck["torch_rng"])
        if dev.type == "cuda" and ck.get("cuda_rng"):
            torch.cuda.set_rng_state_all(ck["cuda_rng"])
        state = ck["state"]
        _log(f"resumed after epoch {state['epoch']} (best PR-AUC {state['best_pr_auc']:.4f})")
    _log(f"model {cfg.model}: {count_parameters(model):,} parameters")

    def checkpoint_meta() -> dict:
        return {"format_version": CHECKPOINT_FORMAT, "model_type": "char_cnn",
                "model_config": config_to_dict(mcfg), "mode": cfg.mode,
                "tokenizer": tokenizer.to_config(), "tokenizer_fingerprint": tokenizer.fingerprint(),
                "scaler": None if scaler is None else scaler.to_config(),
                "data_sha256": data_hashes, "torch_version": str(torch.__version__)}

    n = len(tr.y)
    train_loader = make_loader(tr, cfg.batch_size, generator=gen)
    while (state["epoch"] < cfg.epochs and not state["stopped_early"]):
        epoch = state["epoch"] + 1
        t0 = time.perf_counter()
        model.train()
        total = 0.0
        for ids, feats, y in train_loader:
            loss = loss_fn(model(ids, feats), y)
            opt.zero_grad(set_to_none=True)
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step()
            total += float(loss.detach()) * len(y)
        val_m = binary_metrics(val_data.y, predict(model, va))
        pr_auc = val_m["pr_auc"]
        sched.step(pr_auc)
        row = {"epoch": epoch, "train_loss": total / n, **_summary(val_m),
               "lr": opt.param_groups[0]["lr"], "seconds": round(time.perf_counter() - t0, 1)}
        state["history"].append(row)
        state["epoch"] = epoch
        improved = pr_auc > state["best_pr_auc"]
        if improved:
            state.update(best_pr_auc=pr_auc, best_epoch=epoch, bad_epochs=0)
            _atomic_save({**checkpoint_meta(), "state_dict": model.state_dict(), "epoch": epoch,
                          "val_pr_auc": pr_auc}, best_path)
        else:
            state["bad_epochs"] += 1
            state["stopped_early"] = state["bad_epochs"] >= cfg.patience
        _atomic_save({"state_format": STATE_FORMAT, "config": asdict(cfg), "data_sha256": data_hashes,
                      "model": model.state_dict(), "optimizer": opt.state_dict(),
                      "scheduler": sched.state_dict(), "generator": gen.get_state(),
                      "torch_rng": torch.get_rng_state(),
                      "cuda_rng": torch.cuda.get_rng_state_all() if dev.type == "cuda" else [],
                      "state": state}, last_path)
        _log(f"epoch {epoch:3d}/{cfg.epochs} loss {row['train_loss']:.4f} "
             f"val PR-AUC {pr_auc:.4f} recall@1%FPR {row['recall_at_1pct_fpr']:.4f} "
             f"{row['seconds']}s" + ("  *best*" if improved else f"  (no gain {state['bad_epochs']}/{cfg.patience})"))
    if state["stopped_early"]:
        _log(f"early stop: no improvement for {cfg.patience} epochs")

    # ---- final evaluation of the best epoch
    best = torch.load(best_path, map_location=dev, weights_only=True)
    model.load_state_dict(best["state_dict"])
    evals = {"val": (val_data, va)}
    if with_test:
        test_data = load_split(cfg.mode, "test", splits)
        evals["test"] = (test_data, to_tensors(test_data, tokenizer, scaler, dev, cache_dir))
    results = {}
    for split, (data, t) in evals.items():
        score = predict(model, t)
        results[split] = {"overall": binary_metrics(data.y, score),
                          "slices": slice_metrics(data.y, score, data.slices())}
    report = {
        "mode": cfg.mode, "model": cfg.model,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "config": asdict(cfg), "parameters": count_parameters(model),
        "best_epoch": state["best_epoch"], "epochs_run": state["epoch"],
        "stopped_early": state["stopped_early"], "history": state["history"],
        "device": str(dev) + (f" ({torch.cuda.get_device_name(dev)})" if dev.type == "cuda" else ""),
        "versions": {"python": platform.python_version(), "torch": str(torch.__version__)},
        "data_sha256": data_hashes, "evaluated_splits": list(evals),
        "baseline_val_reference": _baseline_reference(cfg.mode, reports_dir),
        "note": "Probabilities are uncalibrated; threshold 0.5 is only a reference point.",
        "results": results,
    }
    (run_dir / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    reports_dir.mkdir(parents=True, exist_ok=True)
    (reports_dir / f"cnn_{run_dir.name}.json").write_text(  # default run dir: <mode>_<model>
        json.dumps(report, indent=2) + "\n", encoding="utf-8")
    s = _summary(results["val"]["overall"])
    ref = report["baseline_val_reference"]
    _log(f"best epoch {state['best_epoch']}: val PR-AUC {s['pr_auc']:.4f}, "
         f"recall@1%FPR {s['recall_at_1pct_fpr']:.4f}"
         + (f"  | baseline char_ngram_lr: PR-AUC {ref['pr_auc']:.4f}, "
            f"recall@1%FPR {ref['recall_at_1pct_fpr']:.4f}" if ref else ""))
    return report


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    d = TrainConfig()
    ap.add_argument("--mode", choices=MODES, default=d.mode)
    ap.add_argument("--model", choices=("cnn", "hybrid"), default=d.model)
    for name in ("epochs", "batch_size", "patience", "seed", "embed_dim", "channels", "hidden",
                 "max_length", "tail_length"):
        ap.add_argument(f"--{name.replace('_', '-')}", type=int, default=getattr(d, name))
    for name in ("lr", "weight_decay", "dropout", "pos_weight"):
        ap.add_argument(f"--{name.replace('_', '-')}", type=float, default=getattr(d, name))
    ap.add_argument("--kernel-sizes", type=int, nargs="+", default=d.kernel_sizes)
    ap.add_argument("--device", choices=("auto", "cpu", "cuda"), default="auto")
    ap.add_argument("--splits", type=Path, default=SPLITS_DIR)
    ap.add_argument("--run-dir", type=Path, default=None,
                    help="default: artifacts/runs/<mode>_<model>")
    ap.add_argument("--restart", action="store_true", help="ignore an existing last.pt")
    ap.add_argument("--with-test", action="store_true", help="also score test (final comparison only)")
    args = ap.parse_args(argv)
    cfg = TrainConfig(mode=args.mode, model=args.model, epochs=args.epochs,
                      batch_size=args.batch_size, lr=args.lr, weight_decay=args.weight_decay,
                      patience=args.patience, seed=args.seed, embed_dim=args.embed_dim,
                      channels=args.channels, kernel_sizes=list(args.kernel_sizes),
                      hidden=args.hidden, dropout=args.dropout, max_length=args.max_length,
                      tail_length=args.tail_length, pos_weight=args.pos_weight)
    train(cfg, splits=args.splits, run_dir=args.run_dir, device=args.device,
          with_test=args.with_test, restart=args.restart, cache_dir=CACHE_DIR,
          reports_dir=REPORTS_DIR)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
