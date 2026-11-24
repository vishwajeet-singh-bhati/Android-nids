import json
from pathlib import Path

import pandas as pd
import pytest

from sms_detection.config import PROCESSED_DIR
from sms_detection.data.deduplicate import add_dedup_columns


def test_template_variants_share_a_split_group():
    frame = pd.DataFrame(
        {
            "message_id": ["a", "b", "c"],
            "text": [
                "Your OTP is 111111. Visit https://one.example",
                "Your OTP is 222222. Visit https://two.example",
                "Your salary has been credited to your account.",
            ],
        }
    )

    result = add_dedup_columns(frame, near_duplicate=False)

    assert result.loc[0, "split_group"] == result.loc[1, "split_group"]
    assert result.loc[0, "split_group"] != result.loc[2, "split_group"]
    assert result["split_group"].nunique() == 2


@pytest.mark.skipif(
    not all((Path(PROCESSED_DIR) / f"{name}.csv").exists() for name in ("train", "val", "test", "external")),
    reason="processed splits are not present; run prepare_data.py first",
)
def test_processed_splits_are_disjoint_by_group():
    frames = {
        name: pd.read_csv(Path(PROCESSED_DIR) / f"{name}.csv", low_memory=False)
        for name in ("train", "val", "test", "external")
    }
    groups = {
        name: set(frame["split_group"].astype(str))
        for name, frame in frames.items()
    }

    for left, right in (
        ("train", "val"),
        ("train", "test"),
        ("val", "test"),
        ("train", "external"),
        ("val", "external"),
        ("test", "external"),
    ):
        assert groups[left].isdisjoint(groups[right]), (left, right)

    for name, frame in frames.items():
        assert not frame.empty, name
        assert frame["text"].notna().all(), name
        assert set(frame["label"]) <= {"ham", "spam", "smishing"}, name


@pytest.mark.skipif(
    not (Path(PROCESSED_DIR) / "split_manifest.json").exists(),
    reason="split manifest is not present; run prepare_data.py first",
)
def test_split_manifest_matches_files():
    manifest = json.loads(
        (Path(PROCESSED_DIR) / "split_manifest.json").read_text(encoding="utf-8")
    )
    for name in ("train", "val", "test", "external"):
        frame = pd.read_csv(Path(PROCESSED_DIR) / f"{name}.csv", low_memory=False)
        assert int(manifest["splits"][name]["rows"]) == len(frame)
