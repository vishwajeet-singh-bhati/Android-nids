import pandas as pd
import pytest

from sms_detection.data.review import build_pool, select_pilot, finalize_reviews


def pool():
    return build_pool(pd.DataFrame([
        {"text": "Your OTP is 123456. Never share it.", "source": "a", "source_label": "ham"},
        {"text": "Your OTP is 123456. Never share it.", "source": "b", "source_label": "smishing"},
        {"text": "Festival sale: discount on shoes.", "source": "a", "source_label": "spam"},
        {"text": "", "source": "a", "source_label": "ham"},
    ]))


def reviewed():
    registry, _, _ = pool()
    row = registry.iloc[[0]].copy()
    row["label_1"] = row["label_2"] = "ham"
    row["reviewer_1"], row["reviewer_2"] = "alice", "bob"
    return row, registry


def test_conflicting_duplicates_keep_provenance_without_inheriting_labels():
    registry, provenance, stats = pool()
    assert len(registry) == 2
    assert len(provenance) == 3
    assert stats["messages_with_conflicting_source_labels"] == 1
    assert registry.label_1.eq("").all()
    assert "source_label" not in registry
    assert registry.usage.eq("development_only").all()


def test_pilot_is_deterministic_and_has_unique_groups():
    registry, provenance, _ = pool()
    first = select_pilot(registry, provenance, 2)
    pd.testing.assert_frame_equal(first, select_pilot(registry, provenance, 2))
    assert first.group_id.is_unique


def test_no_reviews_export_no_training_labels():
    registry, _, _ = pool()
    accepted, stats = finalize_reviews(registry, registry)
    assert accepted.empty
    assert stats["pending_or_disputed_rows"] == len(registry)
    assert stats["fresh_test_rows"] == 0


def test_agreement_requires_distinct_reviewers():
    row, registry = reviewed()
    row["reviewer_2"] = " ALICE "
    with pytest.raises(ValueError, match="distinct"):
        finalize_reviews(row, registry)


def test_disagreement_needs_explicit_adjudication():
    row, registry = reviewed()
    row["label_2"] = "spam"
    accepted, stats = finalize_reviews(row, registry)
    assert accepted.empty
    row["adjudicated_label"] = "uncertain"
    with pytest.raises(ValueError, match="rationale"):
        finalize_reviews(row, registry)
    row["adjudicator"], row["adjudication_notes"] = "carol", "Authenticity could not be verified"
    accepted, stats = finalize_reviews(row, registry)
    assert accepted.label.tolist() == ["uncertain"]
    assert stats["usable_labelled_rows"] == 0


@pytest.mark.parametrize("field,value", [("text", "modified message"), ("usage", "test"), ("group_id", "new")])
def test_review_cannot_change_identity_or_claim_fresh_test(field, value):
    row, registry = reviewed()
    row[field] = value
    with pytest.raises(ValueError, match="Immutable"):
        finalize_reviews(row, registry)


def test_approved_labels_are_exportable_but_stay_development_only():
    row, registry = reviewed()
    accepted, stats = finalize_reviews(row, registry)
    assert accepted.label.tolist() == ["ham"]
    assert accepted.usage.tolist() == ["development_only"]
    assert stats["usable_labelled_rows"] == 1


def test_unknown_label_and_duplicate_ids_are_rejected():
    row, registry = reviewed()
    row["label_1"] = "safe-ish"
    with pytest.raises(ValueError, match="Invalid label"):
        finalize_reviews(row, registry)
    with pytest.raises(ValueError, match="Duplicate review"):
        finalize_reviews(pd.concat([row, row]), registry)
