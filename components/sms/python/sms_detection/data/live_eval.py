"""Summarize private append-only phone test logs without confusing sends/receipts.

Strict classification recall and warning coverage are intentionally separate.
No precision/accuracy claim is possible on the all-positive handmade set.
"""
from __future__ import annotations
from collections import Counter
import math

def percentile(values, q):
    values = sorted(v for v in values if isinstance(v, (int, float)) and math.isfinite(v) and v >= 0)
    if not values:
        return None
    position = (len(values) - 1) * q
    lo, hi = math.floor(position), math.ceil(position)
    return values[lo] + (values[hi] - values[lo]) * (position - lo)

def summarize(config: dict, events: list[dict]) -> dict:
    receipts, results = {}, {}
    errors = []
    for e in events:
        kind, event_id = e.get("type"), e.get("event_id")
        if kind == "received":
            if not event_id or event_id in receipts:
                errors.append("Missing or duplicate receipt event ID")
                continue
            receipts[event_id] = e
        elif kind in {"completed", "failed"}:
            if not event_id or event_id in results:
                errors.append("Missing or duplicate terminal event ID")
                continue
            results[event_id] = e
    orphan = set(results) - set(receipts)
    if orphan:
        errors.append(f"{len(orphan)} terminal records have no receipt")
    expected = set(config.get("expected_sample_ids", range(1, config["expected_count"] + 1)))
    matched = {key: r for key, r in receipts.items() if r.get("match_kind") in {"exact", "template"} and r.get("sample_id") in expected}
    attempts = Counter(r["sample_id"] for r in matched.values())
    unique = set(attempts)
    completed = {k: results[k] for k in receipts if k in results and results[k].get("type") == "completed"}
    matched_completed = {k: r for k, r in completed.items() if k in matched}
    failures = sum(r.get("type") == "failed" for k, r in results.items() if k in receipts)
    pending = set(receipts) - set(results)
    def tier_counts(data):
        counts = Counter(r.get("tier2_status", "unknown") for r in data.values())
        return {"tier1_only": counts["not_needed"], "tier2_completed": counts["completed"],
            "tier2_failed": sum(n for k, n in counts.items() if k.startswith("failed_")),
            "unknown_status": sum(n for k, n in counts.items() if k not in {"not_needed", "completed"} and not k.startswith("failed_"))}
    # Deterministic first-attempt scoring avoids cherry-picking a successful retry.
    first = {}
    for key, r in sorted(matched.items(), key=lambda item: (item[1].get("received_at_ms", 0), item[0])):
        first.setdefault(r["sample_id"], key)
    details = []
    for sample_id in sorted(expected):
        key = first.get(sample_id)
        receipt = receipts.get(key, {})
        result = results.get(key, {})
        details.append({"sample_id": sample_id, "attempts_received": attempts[sample_id],
            "first_event_id": key, "match_kind": receipt.get("match_kind"),
            "status": "not_received" if key is None else result.get("type", "pending"),
            "tier1_label": result.get("tier1_label"), "tier2_status": result.get("tier2_status"),
            "final_label": result.get("final_label"), "final_risk": result.get("final_risk"),
            "notification_submitted": result.get("notification_submitted", False),
            "attention_required": result.get("attention_required", False),
            "first_notification_ms": result.get("first_notification_ms"),
            "analysis_ms": result.get("analysis_ms")})
    first_completed = [d for d in details if d["status"] == "completed"]
    strict = sum(d["final_label"] == "smishing" for d in first_completed)
    warned = sum(d["final_risk"] in {"suspicious", "high"} for d in first_completed)
    submitted = sum(d["notification_submitted"] for d in first_completed)
    first_keys = {d["first_event_id"] for d in first_completed}
    first_results = {k: r for k, r in completed.items() if k in first_keys}
    timings = {}
    for field in ("tier1_ms", "tier2_ms", "queue_ms", "analysis_ms", "receipt_to_completed_ms", "first_notification_ms"):
        data = [r.get(field) for r in matched_completed.values() if field != "tier2_ms" or r.get("tier2_status") == "completed"]
        timings[field] = {"p50": percentile(data, .5), "p95": percentile(data, .95), "max": percentile(data, 1)}
    return {"run_id": config.get("run_id"), "app_version": config.get("app_version"),
        "expected_unique_samples": len(expected), "received_events_all": len(receipts),
        "completed_events_all": len(completed), "failed_events_all": failures, "pending_events_all": len(pending),
        "matched_received_events": len(matched), "unique_samples_received": len(unique),
        "exact_received_events": sum(r.get("match_kind") == "exact" for r in receipts.values()),
        "template_received_events": sum(r.get("match_kind") == "template" for r in receipts.values()),
        "duplicate_matched_receipts": sum(n - 1 for n in attempts.values()),
        "unmatched_events": sum(r.get("match_kind") == "unmatched" for r in receipts.values()),
        "ambiguous_events": sum(r.get("match_kind") == "ambiguous" for r in receipts.values()),
        "matching_error_events": sum(r.get("match_kind") == "match_error" for r in receipts.values()),
        "distinct_sender_hashes": len({r["sender_hash"] for r in receipts.values() if r.get("sender_hash")}),
        "received_by_sender_hash": dict(Counter(r["sender_hash"] for r in receipts.values() if r.get("sender_hash"))),
        "missing_sample_ids": sorted(expected - unique),
        "first_attempt_completed_samples": len(first_completed),
        "strict_smishing_first_attempt": strict, "review_or_high_first_attempt": warned,
        "notification_submitted_first_attempt": submitted,
        "strict_recall_among_first_attempt_completed": strict / len(first_completed) if first_completed else None,
        "missing_or_failed_not_counted_as_classifier_misses": True,
        "first_attempt_tiers": tier_counts(first_results), "matched_event_tiers": tier_counts(matched_completed),
        "all_event_tiers": tier_counts(completed), "timings_ms_matched_events": timings,
        "validation_errors": errors, "per_sample": details,
        "limitations": ["Previously observed all-positive development set; cannot measure precision or legitimate-message false positives",
            "Not received does not prove app loss: compare a sender ledger and transport/delivery evidence",
            "Template matches allow masked entity changes; inspect altered samples separately",
            "Notification submitted does not prove heads-up presentation or that the user saw it",
            "Failures, unfinished events and duplicates are reported separately; first attempt is scored",
            "Timing begins at app SMS receiver entry, not sender tap or carrier delivery",
            "This is not a controlled battery benchmark"]}
