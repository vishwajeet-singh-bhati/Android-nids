from sms_detection.data.live_eval import summarize

CONFIG = {"run_id": "test", "expected_count": 3, "expected_sample_ids": [1, 2, 3]}
def received(eid, sid, at, kind="exact"):
    return {"type": "received", "event_id": eid, "sample_id": sid, "received_at_ms": at, "match_kind": kind, "sender_hash": "sender1"}
def result(eid, label="smishing", risk="high", tier="completed"):
    return {"type": "completed", "event_id": eid, "final_label": label, "final_risk": risk,
        "tier2_status": tier, "notification_submitted": risk != "low", "analysis_ms": 10}

def test_duplicates_and_successful_retry_do_not_hide_first_miss():
    r = summarize(CONFIG, [received("a", 1, 10), result("a", "ham", "low", "not_needed"),
        received("b", 1, 20), result("b"), received("c", 2, 30), result("c")])
    assert r["unique_samples_received"] == 2
    assert r["duplicate_matched_receipts"] == 1
    assert r["strict_smishing_first_attempt"] == 1
    assert r["first_attempt_tiers"] == {"tier1_only": 1, "tier2_completed": 1, "tier2_failed": 0, "unknown_status": 0}
    assert r["missing_sample_ids"] == [3]

def test_review_coverage_is_not_exact_smishing_classification():
    r = summarize(CONFIG, [received("a", 1, 1), result("a", "spam", "suspicious")])
    assert r["strict_smishing_first_attempt"] == 0
    assert r["review_or_high_first_attempt"] == 1

def test_failure_pending_ambiguous_unmatched_are_separate():
    r = summarize(CONFIG, [received("a", 1, 1), {"type": "failed", "event_id": "a"},
        received("b", 2, 2), received("c", None, 3, "ambiguous"), result("c"),
        received("d", None, 4, "unmatched"), result("d")])
    assert r["failed_events_all"] == 1 and r["pending_events_all"] == 1
    assert r["ambiguous_events"] == 1 and r["unmatched_events"] == 1
    assert r["first_attempt_completed_samples"] == 0
    assert r["strict_recall_among_first_attempt_completed"] is None

def test_terminal_corruption_and_orphan_are_reported():
    r = summarize(CONFIG, [received("a", 1, 1), received("a", 1, 2), result("a"), result("a"), result("orphan")])
    assert len(r["validation_errors"]) == 3

def test_tier2_failure_is_not_tier1_only():
    r = summarize(CONFIG, [received("a", 1, 1), result("a", tier="failed_RuntimeError")])
    assert r["first_attempt_tiers"]["tier2_failed"] == 1
    assert r["first_attempt_tiers"]["tier1_only"] == 0

def test_matching_error_preserves_receipt_and_result_without_forcing_sample_id():
    r = summarize(CONFIG, [received("a", None, 1, "match_error"), result("a")])
    assert r["received_events_all"] == 1
    assert r["completed_events_all"] == 1
    assert r["matching_error_events"] == 1
    assert r["unique_samples_received"] == 0
