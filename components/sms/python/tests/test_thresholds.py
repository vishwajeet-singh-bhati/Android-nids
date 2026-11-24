import numpy as np

from sms_detection.models.calibrate import (
    fit_temperature,
    select_risk_thresholds,
    select_threshold,
)


def test_threshold_selector_respects_precision_and_recall_floors():
    y = [1, 1, 1, 1, 0, 0, 0, 0]
    p = [0.95, 0.85, 0.75, 0.40, 0.35, 0.20, 0.10, 0.05]

    selected = select_threshold(
        y,
        p,
        cost_fn=10.0,
        cost_fp=1.0,
        min_recall=0.75,
        min_precision=1.0,
    )

    assert selected.recall >= 0.75
    assert selected.precision >= 1.0


def test_risk_thresholds_report_feasibility():
    y = ["smishing", "smishing", "ham", "ham"]
    probabilities = np.asarray(
        [
            [0.02, 0.03, 0.95],
            [0.05, 0.10, 0.85],
            [0.90, 0.05, 0.05],
            [0.80, 0.10, 0.10],
        ]
    )

    policy = select_risk_thresholds(
        y,
        probabilities,
        min_high_recall=0.5,
        min_high_precision=1.0,
    )

    assert policy["high_feasible"] is True
    assert policy["high_precision"] == 1.0
    assert policy["suspicious_threshold"] <= policy["high_threshold"]


def test_temperature_is_positive():
    logits = np.asarray([[2.0, 0.0, -1.0], [0.0, 2.0, -1.0]])
    temperature = fit_temperature(logits, ["ham", "spam"])

    assert temperature > 0
