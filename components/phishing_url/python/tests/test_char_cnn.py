import json

import numpy as np
import pytest
import torch

from src.models.char_cnn import CharCNN, CharCNNConfig, count_parameters, load_checkpoint
from src.preprocessing.tokenizer import URLTokenizer
from src.training import train_cnn
from src.training.train_cnn import TrainConfig, train
from tests.test_training import make_rows, write

TOK = URLTokenizer()


def ids_for(texts, max_length=256):
    tok = URLTokenizer(max_length=max_length, tail_length=min(64, max_length // 4))
    return torch.from_numpy(tok.encode_batch(texts).ids)


# ---------------------------------------------------------------- model
def test_forward_shape_and_size():
    model = CharCNN(CharCNNConfig(vocab_size=TOK.vocab_size)).eval()
    out = model(ids_for(["example.com/a", "login-secure.evil.com/x.php"]))
    assert out.shape == (2,) and torch.isfinite(out).all()
    assert 50_000 < count_parameters(model) < 200_000          # small enough for a Pi


def test_padding_is_masked_exactly():
    """Extra padding (longer max_length) must not change the prediction."""
    torch.manual_seed(0)
    model = CharCNN(CharCNNConfig(vocab_size=TOK.vocab_size)).eval()
    texts = ["paypal.com.verify-account.example/login", "a.io"]
    short = model(ids_for(texts, 64))
    long = model(ids_for(texts, 256))
    torch.testing.assert_close(short, long)


def test_hybrid_needs_features():
    model = CharCNN(CharCNNConfig(vocab_size=TOK.vocab_size, num_features=5)).eval()
    ids = ids_for(["a.com", "b.com"])
    assert model(ids, torch.zeros(2, 5)).shape == (2,)
    with pytest.raises(ValueError):
        model(ids)
    with pytest.raises(ValueError):
        CharCNN(CharCNNConfig(vocab_size=TOK.vocab_size)).eval()(ids, torch.zeros(2, 5))


@pytest.mark.parametrize("kw", [{"kernel_sizes": (4,)}, {"dropout": 1.0}, {"vocab_size": 1}])
def test_bad_config(kw):
    with pytest.raises(ValueError):
        CharCNNConfig(**({"vocab_size": 97} | kw))


# ---------------------------------------------------------------- data loading
def _tensors(n=10):
    return train_cnn.Tensors(ids=torch.randint(1, 50, (n, 12), dtype=torch.uint8),
                             lengths=torch.randint(1, 13, (n,)), features=torch.randn(n, 3),
                             y=(torch.arange(n) % 2).float())


def test_shuffled_loader_matches_one_permutation_per_epoch():
    t = _tensors(10)
    loader = train_cnn.make_loader(t, batch_size=4, generator=torch.Generator().manual_seed(5))
    ref = torch.Generator().manual_seed(5)
    for _ in range(2):                                      # two epochs
        perm = torch.randperm(10, generator=ref)
        batches = list(loader)
        assert [len(b[2]) for b in batches] == [4, 4, 2]    # last batch is partial
        for (ids, feats, y), idx in zip(batches, (perm[0:4], perm[4:8], perm[8:10])):
            expected_ids, expected_feats, expected_y = train_cnn._batch(t, idx)
            assert torch.equal(ids, expected_ids) and torch.equal(feats, expected_feats)
            assert torch.equal(y, expected_y)


def test_loader_leaves_the_global_rng_alone():
    """Dropout draws from the global RNG; the loader must not, or training changes."""
    t = _tensors(10)
    torch.manual_seed(0)
    before = torch.get_rng_state()
    for gen in (torch.Generator().manual_seed(1), None):
        list(train_cnn.make_loader(t, batch_size=3, generator=gen))
    assert torch.equal(before, torch.get_rng_state())


def test_ordered_loader_keeps_input_order():
    t = _tensors(7)
    loader = train_cnn.make_loader(t, batch_size=3)
    assert isinstance(loader.dataset, train_cnn.URLDataset) and len(loader.dataset) == 7
    assert torch.equal(torch.cat([y for _, _, y in loader]), t.y)


# ---------------------------------------------------------------- training
@pytest.fixture
def tiny(tmp_path):
    root = tmp_path / "splits"
    for split, (start, count) in {"train": (0, 60), "val": (100, 20), "test": (200, 20)}.items():
        write(root / "full_url" / f"{split}.csv", make_rows(start, count, "full_url"))
    return root


def small(**kw):
    return TrainConfig(**({"epochs": 2, "batch_size": 32, "channels": 8, "embed_dim": 8,
                           "hidden": 8, "lr": 3e-3} | kw))


@pytest.mark.parametrize("model", ["cnn", "hybrid"])
def test_train_resume_and_checkpoint(tiny, tmp_path, model):
    run, reports = tmp_path / "run", tmp_path / "reports"
    kw = dict(splits=tiny, run_dir=run, device="cpu", cache_dir=tmp_path / "c", reports_dir=reports)
    r1 = train(small(model=model), **kw)
    assert r1["epochs_run"] == 2 and (run / "best.pt").exists() and (run / "last.pt").exists()
    assert r1["evaluated_splits"] == ["val"]

    r2 = train(small(model=model, epochs=3), **kw)           # resumes, runs only epoch 3
    assert r2["epochs_run"] == 3 and len(r2["history"]) == 3
    assert r2["history"][:2] == r1["history"]

    m, tok, scaler, meta = load_checkpoint(run / "best.pt")
    assert (scaler is None) == (model == "cnn") and meta["mode"] == "full_url"
    saved = (reports / "cnn_run.json").read_text(encoding="utf-8")   # named after the run dir
    assert "badsite" not in saved and "news1" not in saved    # no URLs in reports


def test_resume_refuses_changed_config(tiny, tmp_path):
    kw = dict(splits=tiny, run_dir=tmp_path / "run", device="cpu", cache_dir=None,
              reports_dir=tmp_path / "r")
    train(small(epochs=1), **kw)
    with pytest.raises(RuntimeError):
        train(small(epochs=2, lr=1e-2), **kw)
    assert train(small(epochs=1, lr=1e-2), restart=True, **kw)["epochs_run"] == 1


def test_resumed_run_matches_uninterrupted(tiny, tmp_path):
    kw = dict(splits=tiny, device="cpu", cache_dir=None, reports_dir=tmp_path / "r")
    full = train(small(epochs=3, dropout=0.3), run_dir=tmp_path / "a", **kw)
    train(small(epochs=1, dropout=0.3), run_dir=tmp_path / "b", **kw)
    resumed = train(small(epochs=3, dropout=0.3), run_dir=tmp_path / "b", **kw)
    for a, b in zip(full["history"], resumed["history"]):
        assert a["train_loss"] == pytest.approx(b["train_loss"], rel=1e-5)


def test_cuda_required_but_missing(tiny, tmp_path, monkeypatch):
    monkeypatch.setattr(torch.cuda, "is_available", lambda: False)
    with pytest.raises(RuntimeError):
        train(small(), splits=tiny, run_dir=tmp_path / "x", device="cuda")


def test_cli(tiny, tmp_path, monkeypatch):
    monkeypatch.setattr(train_cnn, "REPORTS_DIR", tmp_path / "reports")
    monkeypatch.setattr(train_cnn, "CACHE_DIR", tmp_path / "cache")
    out = tmp_path / "run"
    assert train_cnn.main(["--splits", str(tiny), "--run-dir", str(out), "--epochs", "1",
                           "--channels", "8", "--embed-dim", "8", "--hidden", "8",
                           "--device", "cpu", "--with-test"]) == 0
    rep = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert rep["evaluated_splits"] == ["val", "test"]


def test_summarize(tiny, tmp_path, capsys):
    from src.training import summarize
    runs = tmp_path / "runs"
    train(small(epochs=1), splits=tiny, run_dir=runs / "full_url_cnn", device="cpu",
          cache_dir=None, reports_dir=tmp_path / "r")
    rows = summarize.summarize("full_url", runs, tmp_path / "r")
    assert len(rows) == 1 and rows[0][0].startswith("full_url_cnn (cnn, seed 13)")
    assert summarize.main(["--runs", str(runs), "--reports", str(tmp_path / "r")]) == 0
    assert "PR-AUC[homepage_only]" in capsys.readouterr().out
