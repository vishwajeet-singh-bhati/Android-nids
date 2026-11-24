"""Rules-only baseline and risk fusion.

The model is the primary classifier, but explicit, auditable evidence can
escalate a message to review. The escalation logic is deliberately conservative
and is evaluated separately in the baseline report. Risk bands are derived from
uncalibrated model scores plus evidence combinations and review safeguards.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping

from ..config import (
    DEFAULT_COST_FN,
    DEFAULT_COST_FP,
    DEFAULT_EVIDENCE_FREE_HIGH,
    DEFAULT_HIGH_THRESHOLD,
    DEFAULT_SUSPICIOUS_THRESHOLD,
    LABELS,
    POLICY_VERSION,
)
from ..interface.schema import EvidenceItem
from ..preprocessing import indicators as ind
from ..preprocessing.indicators import IndicatorResult
from .action_codes import action_codes


@dataclass(frozen=True)
class RulesDecision:
    label: str
    scores: dict[str, float]
    reason_codes: tuple[str, ...] = ()


@dataclass(frozen=True)
class RiskAssessment:
    label: str
    risk_level: str
    scores: dict[str, float]
    evidence: list[EvidenceItem]
    recommended_action_codes: list[str]
    policy_version: str = POLICY_VERSION
    rule_label: str = "ham"
    rule_triggered: bool = False


# Rules are intentionally high precision, not high coverage. A single keyword
# such as "bank" or "offer" is never sufficient.
def rule_based_classify(result: IndicatorResult) -> RulesDecision:
    flags = result.flags

    def has(*codes: str) -> bool:
        return all(flags.get(code, False) for code in codes)

    def any_of(*codes: str) -> bool:
        return any(flags.get(code, False) for code in codes)

    reasons: list[str] = []

    # Critical: explicit request for an OTP or credentials.
    if has(ind.OTP_REQUEST):
        reasons.append(ind.OTP_REQUEST)
    if has(ind.CREDENTIAL_REQUEST):
        reasons.append(ind.CREDENTIAL_REQUEST)

    # Link plus account-reset / login / password context is a classic
    # account-takeover lure. The indicator already requires a URL and excludes
    # common "if this wasn't you" security-alert phrasing.
    if has(ind.ACCOUNT_ACCESS_LURE):
        reasons.append(ind.ACCOUNT_ACCESS_LURE)

    # Payment demand combined with pressure, impersonation or a link.
    if has(ind.PAYMENT_REQUEST) and any_of(
        ind.ACCOUNT_THREAT,
        ind.URGENCY_LANGUAGE,
        ind.URL_PRESENT,
        ind.IMPERSONATION,
        ind.THREAT_OF_ACTION,
        ind.PRIZE_OR_REWARD_BAIT,
    ):
        reasons.append(ind.PAYMENT_REQUEST)

    # Account/KYC threat that drives the user to a link.
    if has(ind.ACCOUNT_THREAT) and flags.get(ind.URL_PRESENT) and any_of(
        ind.URGENCY_LANGUAGE,
        ind.KYC_LANGUAGE,
        ind.IMPERSONATION,
        ind.THREAT_OF_ACTION,
    ):
        reasons.append(ind.ACCOUNT_THREAT)

    # Prize/lottery bait with a payment, link or urgency hook.
    if has(ind.PRIZE_OR_REWARD_BAIT) and any_of(
        ind.PAYMENT_REQUEST,
        ind.URL_PRESENT,
        ind.URGENCY_LANGUAGE,
        ind.CREDENTIAL_REQUEST,
    ):
        reasons.append(ind.PRIZE_OR_REWARD_BAIT)

    # Loan/job/delivery lure that asks for money or credentials.
    if any_of(ind.LOAN_OR_INVESTMENT_BAIT, ind.JOB_OFFER_BAIT, ind.DELIVERY_BAIT) and any_of(
        ind.PAYMENT_REQUEST, ind.CREDENTIAL_REQUEST, ind.OTP_REQUEST
    ):
        reasons.append("FEE_OR_CREDENTIAL_LURE")

    # Refund bait that asks for credentials/OTP or a payment.
    if has(ind.REFUND_BAIT) and any_of(
        ind.CREDENTIAL_REQUEST, ind.OTP_REQUEST, ind.PAYMENT_REQUEST
    ):
        reasons.append(ind.REFUND_BAIT)

    # Context-gated Indian scam patterns. Each indicator already requires a
    # link or a remote contact channel, so a single keyword is not enough.
    for code in (
        ind.DTH_UTILITY_THREAT,
        ind.TASK_SCAM,
        ind.TELECOM_LURE,
        ind.DATA_HARVESTING,
        ind.HIGH_DEMAND_GADGET_SCAM,
        ind.APK_DOWNLOAD_LURE,
        ind.DELIVERY_UPDATE_LURE,
        ind.SERVICE_INTERRUPTION_LURE,
    ):
        if has(code):
            reasons.append(code)

    if reasons:
        return RulesDecision(label="smishing", scores=_rule_scores("smishing"), reason_codes=tuple(reasons))

    # Generic unwanted promotional/bulk content -> spam. Delivery is only a
    # spam cue when it also carries a link, a fee, urgency or an account threat;
    # a normal "your parcel was delivered" message is not spam.
    spam_lure = any_of(
        ind.PROMOTIONAL_CONTENT,
        ind.LOAN_OR_INVESTMENT_BAIT,
        ind.JOB_OFFER_BAIT,
        ind.PRIZE_OR_REWARD_BAIT,
    ) or (
        flags.get(ind.DELIVERY_BAIT, False)
        and any_of(
            ind.URL_PRESENT,
            ind.PAYMENT_REQUEST,
            ind.URGENCY_LANGUAGE,
            ind.ACCOUNT_THREAT,
        )
    )
    if spam_lure:
        return RulesDecision(label="spam", scores=_rule_scores("spam"), reason_codes=("PROMOTIONAL_OR_LURE",))

    return RulesDecision(label="ham", scores=_rule_scores("ham"))


def _rule_scores(label: str) -> dict[str, float]:
    scores = {name: 0.1 for name in LABELS}
    scores[label] = 0.8
    return scores


def _normalise_scores(scores: Mapping[str, float]) -> dict[str, float]:
    values = {label: max(0.0, float(scores.get(label, 0.0))) for label in LABELS}
    total = sum(values.values())
    if total <= 0:
        return {label: 1.0 / len(LABELS) for label in LABELS}
    return {label: value / total for label, value in values.items()}


@dataclass
class RiskPolicy:
    high_threshold: float = DEFAULT_HIGH_THRESHOLD
    suspicious_threshold: float = DEFAULT_SUSPICIOUS_THRESHOLD
    evidence_free_high_threshold: float = DEFAULT_EVIDENCE_FREE_HIGH
    cost_fn: float = DEFAULT_COST_FN
    cost_fp: float = DEFAULT_COST_FP
    allow_rule_override: bool = True
    policy_version: str = POLICY_VERSION

    def assess(
        self,
        scores: Mapping[str, float],
        result: IndicatorResult,
    ) -> RiskAssessment:
        probabilities = _normalise_scores(scores)
        model_label = max(LABELS, key=lambda label: probabilities[label])
        p_smishing = probabilities["smishing"]
        flags = result.flags
        rules = rule_based_classify(result)

        critical_rule = bool(
            flags.get(ind.OTP_REQUEST)
            or flags.get(ind.CREDENTIAL_REQUEST)
            or flags.get(ind.ACCOUNT_ACCESS_LURE)
            or (
                flags.get(ind.PAYMENT_REQUEST)
                and (flags.get(ind.ACCOUNT_THREAT) or flags.get(ind.THREAT_OF_ACTION))
            )
        )
        pattern_rule = bool(
            flags.get(ind.DTH_UTILITY_THREAT)
            or flags.get(ind.TASK_SCAM)
            or flags.get(ind.TELECOM_LURE)
            or flags.get(ind.DATA_HARVESTING)
            or flags.get(ind.HIGH_DEMAND_GADGET_SCAM)
            or flags.get(ind.APK_DOWNLOAD_LURE)
            or flags.get(ind.DELIVERY_UPDATE_LURE)
            or flags.get(ind.SERVICE_INTERRUPTION_LURE)
        )
        # These rules are only raised for context-gated indicator combinations
        # (normally with a link or remote contact channel). Treat them as
        # high-confidence evidence when deciding whether a model disagreement
        # is safe to override.
        override_rule = critical_rule or pattern_rule
        rule_smishing = rules.label == "smishing"
        strong_count = result.strong_cue_count()
        p_high = p_smishing >= self.high_threshold
        p_very_high = p_smishing >= self.evidence_free_high_threshold
        evidence_high = strong_count > 0 or rule_smishing or critical_rule
        # A high-risk interruption is normally evidence-backed. A very high
        # model score can stand alone so text-only smishing is still caught.
        high_supported = p_high and (evidence_high or p_very_high)

        risk = "low"
        if model_label == "smishing":
            risk = "high" if high_supported else "suspicious"

        # Evidence-based escalation. Critical request patterns and the
        # context-gated Indian scam patterns can override a model disagreement
        # only when the message also carries a link or meaningful model support.
        if rule_smishing:
            if override_rule and (flags.get(ind.URL_PRESENT) or p_smishing >= self.suspicious_threshold):
                risk = "high"
            elif high_supported or (
                p_smishing >= self.suspicious_threshold and strong_count >= 2
            ):
                risk = "high"
            elif risk == "low":
                risk = "suspicious"

        if high_supported:
            risk = "high"
        elif p_smishing >= self.suspicious_threshold and risk == "low":
            risk = "suspicious"

        # Final label. Critical evidence is allowed to override a weak model
        # disagreement; otherwise the model label remains authoritative.
        label = model_label
        if override_rule and (flags.get(ind.URL_PRESENT) or p_smishing >= self.suspicious_threshold):
            label = "smishing"
        elif rule_smishing and p_smishing >= self.suspicious_threshold:
            label = "smishing"
        elif model_label == "ham" and rules.label == "spam" and risk == "suspicious":
            label = "spam"
        if risk == "high":
            label = "smishing"
        elif label == "smishing" and risk == "low":
            risk = "suspicious"

        # Routine "salary credited", "EMI debited", "payment successful" alerts
        # are the dominant false-positive family in the Hinglish seed. The guard
        # only applies when no link, request, threat or promotional cue exists,
        # so a "debited, call this number" lure is not suppressed.
        if flags.get(ind.BENIGN_TRANSACTIONAL, False) or flags.get(
            ind.BENIGN_DELIVERY, False
        ):
            label = "ham"
            risk = "low"

        # Context patterns also occur in genuine bills, recharge offers and
        # delivery updates. Without an explicit credential request, retain the
        # model verdict and request review instead of asserting fraud.
        explicit_secret_request = bool(
            flags.get(ind.OTP_REQUEST)
            or flags.get(ind.CREDENTIAL_REQUEST)
            or flags.get(ind.ACCOUNT_ACCESS_LURE)
        )
        if pattern_rule and not explicit_secret_request:
            label = model_label
            risk = "suspicious"

        # Ordinary promotions are unwanted content, not a security incident.
        # A low smishing score alone must not turn ham/spam into an alert.
        if not rule_smishing and model_label != "smishing" and not high_supported:
            risk = "low"

        actions = action_codes(label, risk, flags)
        return RiskAssessment(
            label=label,
            risk_level=risk,
            scores=probabilities,
            evidence=list(result.items),
            recommended_action_codes=actions,
            policy_version=self.policy_version,
            rule_label=rules.label,
            rule_triggered=rules.label != "ham",
        )
