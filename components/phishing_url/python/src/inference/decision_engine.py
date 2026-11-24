"""Combine the model, threat intelligence and a few safety rules into one decision.

Rules, in order. Threat intelligence can only raise the risk, never lower it.
  1. This exact page or this host is listed as PHISHING (local feeds or
     Google) -> PHISHING, source "threat_intel", whatever the model says.
  2. Link shortener / QR redirector -> UNCERTAIN, source "rule": the real
     destination is hidden, and the model was not trained on such links.
  3. No model result (domain-only input, for which there is no hostname model
     yet, or a model failure) -> UNCERTAIN, source "rule".
  4. Otherwise the calibrated model decision, source "model". Popular-website
     guard: on the most popular websites (bundle popular.txt, Tranco top
     1,000) the model alone may not say PHISHING; it says UNCERTAIN, source
     "rule". Real login pages there look like phishing to a URL-only model
     (github.com/login: 0.968). Phishing pages listed by a feed or Google are
     still PHISHING by rule 1. The guard never gives LIKELY_SAFE, so no
     website is ever marked safe because it is popular.
  5. Listed as malware / unwanted software / harmful app -> at least
     UNCERTAIN. Dangerous, but not phishing, so it is not labelled phishing.
  6. Another host under the same registered domain is listed -> LIKELY_SAFE
     becomes UNCERTAIN.
"no_match", "unavailable" and "pending" from a threat-intel source never
lower the risk; they are reported in `reasons` ("not listed" is not evidence
of safety).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from src.intelligence.results import (EXACT_URL, HOSTNAME, MATCH, PENDING, PHISHING_THREAT,
                                      REGISTERED_DOMAIN, UNAVAILABLE, IntelMatch, IntelResult)
from src.models.calibration import LIKELY_SAFE, OUTCOMES, PHISHING, UNCERTAIN

RANK = {LIKELY_SAFE: 0, UNCERTAIN: 1, PHISHING: 2}
MODEL, THREAT_INTEL, RULE = "model", "threat_intel", "rule"


@dataclass(frozen=True)
class Decision:
    decision: str                      # PHISHING / UNCERTAIN / LIKELY_SAFE
    risk_score: float | None           # calibrated model P(phishing); None if no model ran
    source: str                        # what set the decision: model / threat_intel / rule
    reasons: tuple[str, ...]
    threat_types: tuple[str, ...]      # from threat intelligence ("phishing", "malware", ...)
    matches: tuple[IntelMatch, ...]
    attributions: tuple[str, ...]      # notices a provider requires next to a warning


def _describe(ms: list[IntelMatch]) -> str:
    return ", ".join(sorted({f"{m.source} ({m.level})" for m in ms}))


def decide(*, input_type: str, model_probability: float | None, model_outcome: str | None,
           intel: Mapping[str, IntelResult], is_redirector: bool, is_popular: bool = False,
           model_note: str = "") -> Decision:
    if model_outcome is not None and model_outcome not in OUTCOMES:
        raise ValueError(f"model_outcome must be one of {OUTCOMES}")
    matches = [m for r in intel.values() if r.status == MATCH for m in r.matches]
    strong = [m for m in matches if m.level in (EXACT_URL, HOSTNAME)]
    phishing = [m for m in strong if PHISHING_THREAT in m.threat_types]
    other = [m for m in strong if PHISHING_THREAT not in m.threat_types]
    siblings = [m for m in matches if m.level == REGISTERED_DOMAIN]
    reasons: list[str] = []

    if phishing:
        decision, source = PHISHING, THREAT_INTEL
        reasons.append(f"listed as phishing by {_describe(phishing)}")
    elif is_redirector:
        decision, source = UNCERTAIN, RULE
        reasons.append("link shortener / QR redirector: the real destination is hidden")
    elif model_outcome is None:
        decision, source = UNCERTAIN, RULE
        reasons.append(model_note or ("domain-only input: there is no hostname model yet, "
                                      "only threat intelligence was checked"
                                      if input_type == "domain" else "no model result"))
    else:
        decision, source = model_outcome, MODEL
        reasons.append(f"model: {model_outcome} (P(phishing) = {model_probability:.3f})")
        if is_popular and decision == PHISHING:
            decision, source = UNCERTAIN, RULE
            reasons.append("popular website: the model alone does not call pages here phishing "
                           "(real login pages look like phishing from the URL); only a threat-list "
                           "match does")

    if other:
        kinds = sorted({t for m in other for t in m.threat_types})
        reasons.append(f"listed as {'/'.join(kinds)} (not phishing) by {_describe(other)}")
        if RANK[decision] < RANK[UNCERTAIN]:
            decision, source = UNCERTAIN, THREAT_INTEL
    if siblings:
        reasons.append(f"another host on this domain is listed by {_describe(siblings)}")
        if decision == LIKELY_SAFE:
            decision, source = UNCERTAIN, THREAT_INTEL
    for name, r in intel.items():
        if r.status == UNAVAILABLE:
            reasons.append(f"{name} unavailable ({r.reason})")
        elif r.status == PENDING:
            reasons.append(f"{name} check is running in the background (ask again for its answer)")
        elif r.stale:
            reasons.append(f"{name} data is stale (feeds updated {r.feeds_updated_at})")
    if not matches:
        reasons.append("not on any threat list checked (this is not evidence of safety)")
    return Decision(decision, model_probability, source, tuple(reasons),
                    tuple(sorted({t for m in matches for t in m.threat_types})), tuple(matches),
                    tuple(sorted({m.attribution for m in matches if m.attribution})))
