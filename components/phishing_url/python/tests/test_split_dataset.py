import csv
import json

import pytest

from src.data.build_dataset import COLUMNS
from src.data.split_dataset import (
    SplitValidationError,
    assign_split,
    build_splits,
    cap_rows,
    drop_label_conflicts,
    load_redirectors,
    opaque_candidates,
    validate_splits,
)
from src.preprocessing.url_normalizer import normalize_url, private_registered_domain


def sample(label, value, input_type="full_url", tranco_rank="", collected="2026-11-13T00:00:00+00:00"):
    n = normalize_url(value, input_type)
    return {
        "sample_id": f"{label[0]}{abs(hash((label, n.canonical))) % 10**12:012d}", "label": label,
        "label_quality": "x", "sources": "test", "input_type": n.input_type,
        "canonical": n.canonical, "model_string": n.model_string, "host": n.host,
        "registered_domain": n.registered_domain, "group": n.registered_domain or n.host,
        "scheme": n.scheme or "", "has_path_or_query": "", "is_ip": str(n.is_ip),
        "has_punycode": str(n.has_punycode), "first_seen": "", "first_collected_at": collected,
        "tranco_rank": tranco_rank, "host_conflict": "False",
    }


def write_samples(path, rows):
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    return path


def read(path):
    with path.open(encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def all_rows(out, mode):
    return [r | {"split": p.stem} for p in sorted((out / mode).glob("*.csv")) for r in read(p)]


# --------------------------------------------------------------------- helpers
def test_private_registered_domain():
    assert private_registered_domain("login.evil.web.app") == "evil.web.app"
    assert private_registered_domain("docs.google.com") == "google.com"


def test_load_redirectors(tmp_path):
    p = tmp_path / "r.txt"
    p.write_text("# comment\nBIT.LY\n\nqrco.de  # inline\nnot a domain\n../x\n", encoding="utf-8")
    assert load_redirectors([p]) == {"bit.ly", "qrco.de"}


def test_assign_split_is_deterministic_and_roughly_proportional():
    assert assign_split("example.com", 1) == assign_split("example.com", 1)
    counts = {"train": 0, "val": 0, "test": 0}
    for i in range(5000):
        counts[assign_split(f"d{i}.com", 1)] += 1
    assert 3800 < counts["train"] < 4200 and 350 < counts["val"] < 650


def test_cap_rows_is_per_split_label_group():
    rows = [{"split": "train", "label": "phishing", "group": "g", "sample_id": str(i)} for i in range(10)]
    rows += [{"split": "train", "label": "benign", "group": "g", "sample_id": f"b{i}"} for i in range(3)]
    kept, removed = cap_rows(rows, 4)
    assert removed == 6 and len(kept) == 7
    assert cap_rows(list(reversed(rows)), 4)[0] == kept or sorted(
        r["sample_id"] for r in cap_rows(list(reversed(rows)), 4)[0]) == sorted(r["sample_id"] for r in kept)


def test_drop_label_conflicts():
    rows = [{"model_string": "a", "label": "phishing"}, {"model_string": "a", "label": "benign"},
            {"model_string": "b", "label": "benign"}]
    kept, removed = drop_label_conflicts(rows)
    assert removed == 2 and kept == [{"model_string": "b", "label": "benign"}]


def test_opaque_candidates():
    rows = [{"group": "short.example", "model_string": f"short.example/c{i}"} for i in range(25)]
    rows += [{"group": "site.example", "model_string": f"site.example/a/b/{i}.php"} for i in range(25)]
    rows += [{"group": "tiny.example", "model_string": "tiny.example/x"}]
    assert opaque_candidates(rows) == [["short.example", 25, 1.0]]


def test_validate_splits_detects_leakage():
    ok = [{"group": "a", "model_string": "a/1", "split": "train", "y": 1, "label": "phishing", "sample_id": "1"},
          {"group": "b", "model_string": "b/1", "split": "test", "y": 0, "label": "benign", "sample_id": "2"}]
    assert all(validate_splits(ok).values())
    leak = ok + [{"group": "a", "model_string": "a/2", "split": "test", "y": 1, "label": "phishing", "sample_id": "3"}]
    with pytest.raises(SplitValidationError):
        validate_splits(leak)
    dup = ok + [dict(ok[0], sample_id="9")]
    validate_splits(dup)  # same group+text+split twice is not leakage
    with pytest.raises(SplitValidationError):
        validate_splits(ok + [dict(ok[0])])  # duplicate id


# --------------------------------------------------------------------- end to end
@pytest.fixture
def samples(tmp_path):
    rows = [
        sample("phishing", "https://bit.ly/abc123"),                           # listed shortener
        sample("phishing", "https://q-r.to/xYz"),                              # local list
        sample("phishing", "https://login.evil.web.app/verify/account"),       # platform tenant
        sample("phishing", "https://docs.google.com/forms/d/e/1FAIpQL/viewform",
               tranco_rank="1"),                                               # popular own domain
        sample("phishing", "https://secure-update.example-bad.net/a/b.php"),
        sample("phishing", "https://same.example.org/x"),                      # label conflict
        sample("benign", "https://same.example.org/x", tranco_rank="50"),
        sample("benign", "https://www.google.com/search/about", tranco_rank="1"),
        sample("benign", "https://news.popular.org/world/123", tranco_rank="7"),
        sample("benign", "google.com", "domain", tranco_rank="1"),
        sample("benign", "web.app", "domain", tranco_rank="900"),
    ]
    rows += [sample("phishing", f"https://bulk.example-farm.com/p/{i}") for i in range(8)]
    return write_samples(tmp_path / "samples.csv", rows)


@pytest.fixture
def lists(tmp_path):
    public = tmp_path / "public.txt"
    public.write_text("bit.ly\n", encoding="utf-8")
    local = tmp_path / "local.txt"
    local.write_text("q-r.to\n", encoding="utf-8")
    return [public, local]


def test_end_to_end(tmp_path, samples, lists):
    out = tmp_path / "splits"
    report = build_splits(samples, out, lists, cap_per_group=5)
    full = all_rows(out, "full_url")
    texts = {r["model_string"] for r in full}

    assert "bit.ly/abc123" not in texts and "q-r.to/xYz" not in texts
    assert report["full_url"]["redirectors_removed"] == {"phishing": 2}
    assert "same.example.org/x" not in texts and report["full_url"]["label_conflicts"] == 2
    assert sum(r["group"] == "example-farm.com" for r in full) == 5           # capped
    assert report["full_url"]["capped"] == 3
    tenant = next(r for r in full if r["host"] == "login.evil.web.app")
    assert tenant["group"] == "evil.web.app" and tenant["y"] == "1"
    assert all(v for v in report["full_url"]["validation"].values())
    assert all(r["sample_id"] for r in full)

    domain = {r["model_string"]: r for r in all_rows(out, "domain")}
    assert domain["login.evil.web.app"]["label"] == "phishing"
    assert "docs.google.com" not in domain                                  # popular own domain
    assert domain["google.com"]["label"] == "benign"
    assert "bit.ly" not in domain and "q-r.to" not in domain
    # docs.google.com (popular own domain) + same.example.org (its group also has benign pages)
    assert report["domain"]["removed"]["phishing_on_popular_domain"] == 2

    # group consistency: a group lands in the same split in both datasets
    full_split = {r["group"]: r["split"] for r in full}
    for r in domain.values():
        if r["group"] in full_split:
            assert full_split[r["group"]] == r["split"]

    saved = json.loads((out / "split_report.json").read_text(encoding="utf-8"))
    assert saved["full_url"]["splits"] == report["full_url"]["splits"]
    assert "shortcut_monitors" in saved["domain"]
    assert "/verify/account" not in (out / "split_report.json").read_text(encoding="utf-8")


def test_deterministic_and_seed_sensitive(tmp_path, samples, lists):
    a = build_splits(samples, tmp_path / "a", lists)
    b = build_splits(samples, tmp_path / "b", lists)
    assert all_rows(tmp_path / "a", "full_url") == all_rows(tmp_path / "b", "full_url")
    assert a["full_url"]["splits"] == b["full_url"]["splits"]


def test_future_cutoff(tmp_path, lists):
    rows = [sample("phishing", "https://old.example-a.com/x", collected="2026-11-01T00:00:00+00:00"),
            sample("phishing", "https://new.example-b.com/x", collected="2026-11-20T00:00:00+00:00"),
            sample("benign", "https://ok.example-c.com/x")]
    path = write_samples(tmp_path / "s.csv", rows)
    build_splits(path, tmp_path / "o", lists, future_cutoff="2026-11-15T00:00:00+00:00")
    future = read(tmp_path / "o" / "full_url" / "test_future.csv")
    assert [r["host"] for r in future] == ["new.example-b.com"]


@pytest.mark.parametrize("kwargs", [{"fractions": (0.5, 0.5)}, {"fractions": (0.9, 0.2, -0.1)},
                                    {"cap_per_group": 0}, {"group_by": "host"},
                                    {"future_cutoff": "yesterday"}])
def test_bad_arguments(tmp_path, samples, lists, kwargs):
    with pytest.raises(ValueError):
        build_splits(samples, tmp_path / "o", lists, **kwargs)


def test_bad_samples_file(tmp_path, lists):
    p = tmp_path / "s.csv"
    p.write_text("a,b\n1,2\n", encoding="utf-8")
    with pytest.raises(ValueError):
        build_splits(p, tmp_path / "o", lists)
