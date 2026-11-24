import json

import pandas as pd
import pytest

from sms_detection.data.indian_sms import (
    BenchmarkFormatError,
    check_leakage,
    load_benchmark,
    load_reference_splits,
    normalize_benchmark,
)
from sms_detection.interface.schema import SmsDetectionResult
from sms_detection.models.indian_eval import (
    bootstrap_macro_f1,
    evaluate_benchmark,
    render_markdown,
    wilson_interval,
)
from sms_detection.policy.risk_fusion import RiskPolicy


class DummyDetector:
    model_version = "dummy-model"
    policy = RiskPolicy()
    metadata = {"selected_experiment": "dummy"}

    def predict_sms(self, text, sender=None, *, known_sender=False):
        if "otp" in text.lower():
            return SmsDetectionResult(
                label="smishing",
                risk_level="high",
                scores={"ham": 0.05, "spam": 0.05, "smishing": 0.90},
            )
        return SmsDetectionResult(
            label="ham",
            risk_level="low",
            scores={"ham": 0.90, "spam": 0.05, "smishing": 0.05},
        )


def benchmark_frame() -> pd.DataFrame:
    return pd.DataFrame(
        {
            "eval_id": ["e1", "e2", "e3", "e4"],
            "text": [
                "Your OTP is 123456. Share it now.",
                "Your OTP is 654321. Share it now.",
                "Your salary has been credited.",
                "Are we meeting for lunch?",
            ],
            "label": ["smishing", "smishing", "ham", "ham"],
            "language": ["en", "hi-Latn", "en", "en"],
            "sender_type": ["10digit", "10digit", "dlt_transactional", "10digit"],
            "scam_type": ["otp", "otp", "none", "none"],
            "collection_month": ["2026-01", "2026-01", "2026-01", "2026-02"],
            "source": ["pilot", "pilot", "pilot", "pilot"],
            "group_id": ["g1", "g2", "g3", "g4"],
            "known_sender": [False, False, False, False],
        }
    )


def test_load_benchmark_maps_aliases_and_optional_metadata(tmp_path):
    path = tmp_path / "benchmark.csv"
    pd.DataFrame(
        {
            "message": ["Hello", "Scam message", "Unclear"],
            "label": ["legitimate", "phishing", "uncertain"],
            "language": ["en", "hi-Latn", "en"],
            "sender_type": ["10digit", "dlt_promotional", "unknown"],
            "scam_type": ["none", "kyc", "unknown"],
            "collection_date": ["2026-01-02", "2026-02-03", ""],
            "known_sender": ["true", "false", "false"],
        }
    ).to_csv(path, index=False)

    frame = load_benchmark(path)

    assert frame["label"].tolist() == ["ham", "smishing", "uncertain"]
    assert frame["language"].tolist() == ["en", "hi-Latn", "en"]
    assert frame["collection_month"].tolist()[0] == "2026-01"
    assert frame["known_sender"].tolist() == [True, False, False]
    assert frame.attrs["input_rows"] == 3


def test_unknown_benchmark_label_is_rejected():
    with pytest.raises(BenchmarkFormatError, match="Unknown benchmark labels"):
        normalize_benchmark(
            pd.DataFrame({"text": ["Hello"], "label": ["mystery"]})
        )


def test_load_benchmark_accepts_kaggle_msg_and_label_columns(tmp_path):
    path = tmp_path / "kaggle.csv"
    pd.DataFrame({"Msg": ["Hello", "Prize waiting"], "Label": ["ham", "spam"]}).to_csv(
        path, index=False
    )

    frame = load_benchmark(path)

    assert frame["text"].tolist() == ["Hello", "Prize waiting"]
    assert frame["label"].tolist() == ["ham", "spam"]


def test_leakage_check_drops_exact_training_overlap_without_exposing_text():
    benchmark = pd.DataFrame(
        {
            "eval_id": ["b1"],
            "text": ["Your OTP is 123456. Share it now."],
            "label": ["smishing"],
        }
    )
    references = {
        "train": pd.DataFrame({"text": ["Your OTP is 123456. Share it now."]})
    }

    filtered, stats = check_leakage(
        benchmark, references, drop_overlaps=True, near_duplicate=False
    )

    assert filtered.empty
    assert stats["checked"] is True
    assert stats["overlap_rows"] == 1
    assert stats["dropped_rows"] == 1
    assert "123456" not in json.dumps(stats)


def test_leakage_check_can_report_without_dropping():
    benchmark = pd.DataFrame(
        {
            "eval_id": ["b1"],
            "text": ["Your OTP is 123456. Share it now."],
            "label": ["smishing"],
        }
    )
    references = {"train": pd.DataFrame({"text": ["Your OTP is 123456. Share it now."]})}

    kept, stats = check_leakage(
        benchmark, references, drop_overlaps=False, near_duplicate=False
    )

    assert len(kept) == 1
    assert kept.loc[0, "leakage_splits"] == "train"
    assert stats["dropped"] is False


def test_leakage_check_reports_distinct_benchmark_groups():
    benchmark = pd.DataFrame(
        {
            "eval_id": ["b1", "b2"],
            "text": [
                "Your OTP is 123456. Share it now.",
                "A genuinely separate ham message for the group count.",
            ],
            "label": ["smishing", "ham"],
        }
    )
    references = {
        "train": pd.DataFrame({"text": ["Your OTP is 123456. Share it now."]})
    }

    _, stats = check_leakage(
        benchmark, references, drop_overlaps=False, near_duplicate=False
    )

    assert stats["benchmark_groups"] == 2
    assert stats["overlap_groups"] == 1
    assert stats["overlap_rows"] == 1


def test_processed_reference_loader_only_returns_text(tmp_path):
    pd.DataFrame({"text": ["one"], "label": ["ham"]}).to_csv(
        tmp_path / "train.csv", index=False
    )
    pd.DataFrame({"text": ["two"], "label": ["smishing"]}).to_csv(
        tmp_path / "external.csv", index=False
    )

    references = load_reference_splits(tmp_path)

    assert set(references) == {"train", "external"}
    assert references["train"].columns.tolist() == ["text"]


def test_wilson_and_bootstrap_intervals_are_valid():
    interval = wilson_interval(5, 10)
    assert 0.0 <= interval["low"] < 0.5 < interval["high"] <= 1.0

    bootstrap = bootstrap_macro_f1(
        ["ham", "ham", "smishing", "smishing"],
        ["ham", "ham", "smishing", "smishing"],
        replicates=20,
    )
    assert bootstrap is not None
    assert 0.0 <= bootstrap["low"] <= bootstrap["high"] <= 1.0


def test_evaluate_benchmark_reports_policy_slices_and_text_free_output():
    report = evaluate_benchmark(
        benchmark_frame(),
        DummyDetector(),
        name="pilot",
        metadata={"input_rows": 4, "leakage": {"checked": False}},
        target_prevalence=0.10,
        bootstrap_replicates=20,
        min_slice_rows=1,
    )
    encoded = json.dumps(report)

    assert report["benchmark"]["name"] == "pilot"
    assert report["policy_metrics"]["smishing_recall"] == 1.0
    assert report["policy_metrics"]["smishing_precision"] == 1.0
    assert report["risk"]["high_smishing_precision"] == 1.0
    assert report["risk"]["ham_high_rate"] == 0.0
    assert report["prevalence_adjusted"]["target_smishing_prevalence"] == 0.10
    assert report["prevalence_adjusted"]["policy_smishing_precision"] == 1.0
    assert "language" in report["slices"]
    assert "123456" not in encoded
    assert "Your OTP" not in encoded
    assert "Are we meeting" not in encoded

    markdown = render_markdown(report)
    assert "Indian SMS Benchmark Evaluation — pilot" in markdown
    assert "Your OTP" not in markdown
    assert "Are we meeting" not in markdown


def test_evaluate_benchmark_rejects_uncertain_labels():
    frame = benchmark_frame()
    frame.loc[0, "label"] = "uncertain"

    with pytest.raises(ValueError, match="outside"):
        evaluate_benchmark(frame, DummyDetector(), name="bad")


def test_binary_spam_benchmark_reports_binary_metrics_without_text():
    frame = pd.DataFrame(
        {
            "text": [
                "Hello, are we meeting today?",
                "Congratulations, claim your prize now",
                "Your OTP is 123456",
                "Lunch at one?",
            ],
            "label": ["ham", "spam", "spam", "ham"],
        }
    )

    report = evaluate_benchmark(
        frame,
        DummyDetector(),
        name="binary-source",
        bootstrap_replicates=0,
        min_slice_rows=1,
    )

    binary = report["binary_spam_metrics"]
    assert binary["support"] == 2
    assert binary["ham_support"] == 2
    assert binary["policy_any_non_ham"]["true_positive"] == 1
    assert binary["policy_exact_spam"]["true_positive"] == 0
    assert "no smishing labels" in report["limitations"][1].lower()
    encoded = json.dumps(report)
    assert "Your OTP" not in encoded
    assert "claim your prize" not in encoded

    markdown = render_markdown(report)
    assert "Binary spam/ham view" in markdown
    assert "No smishing labels" in markdown
    assert "Your OTP" not in markdown
