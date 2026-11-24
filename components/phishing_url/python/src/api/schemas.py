"""Request and response formats of the API (Pydantic models).

They are the contract with the NIDS: FastAPI checks every request against them
(422 on a mismatch) and publishes them at /openapi.json and /docs.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

DecisionName = Literal["phishing", "uncertain", "likely_safe"]


class PredictRequest(BaseModel):
    """One consistent batch format for one URL or many."""
    model_config = ConfigDict(extra="forbid", json_schema_extra={"examples": [
        {"urls": ["https://example.com/", "http://login-verify.example.net/signin"], "input_type": "full_url"}]})

    urls: list[str] = Field(min_length=1, description=(
        "Full URLs, or bare hostnames when input_type is 'domain'. Answered in the same order. "
        "At most max_urls_per_request per call (see /model-info); an invalid entry gets its own "
        "result with `error` and does not fail the others."))
    input_type: Literal["full_url", "domain"] = Field(
        "full_url", description="'domain' for hostnames only (e.g. from DNS or TLS SNI).")


class ThreatIntelMatch(BaseModel):
    source: str = Field(description="local_feeds or google_safe_browsing")
    level: str = Field(description="exact_url, hostname or registered_domain")
    threat_types: list[str]
    count: int
    last_seen: str | None
    expires_at: str | None


class PredictionItem(BaseModel):
    url: str = Field(description="The input as given.")
    input_type: str
    decision: DecisionName | None = Field(description="null only when the input was invalid (see `error`).")
    risk_score: float | None = Field(description="Calibrated model P(phishing), 0..1; null if no model ran "
                                                 "(domain input, link shortener, invalid input).")
    source: str | None = Field(description="What set the decision: model, threat_intel or rule.")
    model_version: str | None
    cache_hit: bool
    reasons: list[str] = Field(description="Plain-language reasons, e.g. for the Llama advisory.")
    threat_types: list[str]
    attributions: list[str] = Field(description="Notices a provider requires next to a warning.")
    threat_intel: list[ThreatIntelMatch]
    pending: list[str] = Field(description="Online checks still running; ask again later for their answer.")
    error: str | None = Field(description="Why the input was invalid, e.g. invalid_input:no_host.")


class PredictResponse(BaseModel):
    results: list[PredictionItem]
    model_version: str | None
    request_id: str


class HealthResponse(BaseModel):
    status: Literal["ok"]


class ReadyResponse(BaseModel):
    ready: bool
    model_version: str | None
    reason: str | None = None


class ErrorResponse(BaseModel):
    detail: str
