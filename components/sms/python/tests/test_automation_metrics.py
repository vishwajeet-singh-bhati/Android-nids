"""Guard the meaning of the reported scam metrics, especially ambiguous labels."""
import importlib.util
from pathlib import Path

import pandas as pd

path = Path(__file__).resolve().parents[1] / "experiments/automation_review/run_desktop.py"
spec = importlib.util.spec_from_file_location("automation_metrics", path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

def test_warning_metrics_separate_review_from_exact_scam_classification():
    frame = pd.DataFrame([
        ("a", "smishing", "spam", "suspicious", True),
        ("b", "smishing", "ham", "low", False),
        ("c", "ham", "smishing", "high", True),
        ("d", "spam", "spam", "low", False),
        ("e", "uncertain", "smishing", "high", True),
    ], columns=["id", "label", "final_label", "final_risk", "routed"])
    frame["scenario_id"] = frame.id
    frame["family"] = "metric_check"
    frame["language"] = "en"
    frame["attention"] = False
    frame["financial"] = False
    frame["any_attention"] = [False, False, True, True, True]
    frame["routing_reason"] = "test"
    result = module.metrics(frame)
    assert result["warning_recall"] == .5
    assert result["warning_precision"] == .5
    assert result["smishing_label_recall"] == 0
    assert result["exact_label_accuracy_known"] == .25
    assert result["uncertain_reviewed"] == 1
    assert result["ham_warned"] == 1
    assert result["tier2_called"] == 3
    assert result["non_scams_any_attention"] == 2
    assert result["scams_any_attention"] == 0

def test_binary_spam_is_not_a_confirmed_nonfraud_negative():
    result = {"ham_support": 5, "ham_warned": 1, "spam_warned": 3,
        "warning_precision": .5, "non_scams_any_attention": 4,
        "language_slices": {"unknown": {"non_scams": 10, "non_scams_warned": 4}},
        "failures": [{"label": "spam"}, {"label": "ham"}]}
    cleaned = module.binary_control_metrics(result)
    assert cleaned["warning_precision"] is None
    assert cleaned["non_scams_any_attention"] is None
    assert cleaned["failures"] == [{"label": "ham"}]
    assert cleaned["language_slices"]["unknown"]["non_scams"] == 5
    assert not cleaned["fraud_ground_truth_available"]
